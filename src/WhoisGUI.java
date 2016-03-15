//author: Nagabhushan S Baddi 
//WhoisGUI is a Whois client that can use for queries for persons, domain, ASN, network, etc 

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.EventQueue;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.UnknownHostException;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.WindowConstants;

@SuppressWarnings("serial")
public class WhoisGUI extends JFrame {

  private JTextField searchString = new JTextField(30);
  private JTextArea names = new JTextArea(15, 80);
  private JButton findButton = new JButton("Find");;
  private ButtonGroup searchIn = new ButtonGroup();
  private ButtonGroup searchFor = new ButtonGroup();
  private JCheckBox exactMatch = new JCheckBox("Exact Match", true);
  private JTextField chosenServer = new JTextField();
  private WhoisQuery server;
  
  public WhoisGUI(WhoisQuery whois) {
    super("Whois");
    this.server = whois;    
    Container pane = this.getContentPane();
    
    Font f = new Font("Monospaced", Font.PLAIN, 12);
    names.setFont(f);
    names.setEditable(false);
    
    JPanel centerPanel = new JPanel();
    centerPanel.setLayout(new GridLayout(1, 1, 10, 10));
    JScrollPane jsp = new JScrollPane(names);
    centerPanel.add(jsp);
    pane.add("Center", centerPanel);   
    
    // You don't want the buttons in the south and north
    // to fill the entire sections so add Panels there
    // and use FlowLayouts in the Panel
    JPanel northPanel = new JPanel();
    JPanel northPanelTop = new JPanel();
    northPanelTop.setLayout(new FlowLayout(FlowLayout.LEFT));
    northPanelTop.add(new JLabel("Whois: "));
    northPanelTop.add("North", searchString);
    northPanelTop.add(exactMatch);
    northPanelTop.add(findButton);
    northPanel.setLayout(new BorderLayout(2,1));
    northPanel.add("North", northPanelTop);
    JPanel northPanelBottom = new JPanel();
    northPanelBottom.setLayout(new GridLayout(1,3,5,5));
    northPanelBottom.add(initRecordType());
    northPanelBottom.add(initSearchFields());
    northPanelBottom.add(initServerChoice());
    northPanel.add("Center", northPanelBottom);

    pane.add("North", northPanel);
      
    ActionListener al = new LookupNames();  
    findButton.addActionListener(al);
    searchString.addActionListener(al);
  }
  
  private JPanel initRecordType() {
    JPanel p = new JPanel();
    p.setLayout(new GridLayout(6, 2, 5, 2));
    p.add(new JLabel("Search for:"));
    p.add(new JLabel(""));
    
    JRadioButton any = new JRadioButton("Any", true);
    any.setActionCommand("Any");
    searchFor.add(any);
    p.add(any);

    p.add(this.makeRadioButton("Network"));
    p.add(this.makeRadioButton("Person"));
    p.add(this.makeRadioButton("Host"));
    p.add(this.makeRadioButton("Domain"));
    p.add(this.makeRadioButton("Organization"));
    p.add(this.makeRadioButton("Group"));
    p.add(this.makeRadioButton("Gateway"));
    p.add(this.makeRadioButton("ASN"));

    return p;
  }

  private JRadioButton makeRadioButton(String label) {
    JRadioButton button = new JRadioButton(label, false);
    button.setActionCommand(label);
    searchFor.add(button);
    return button;
  }

  private JRadioButton makeSearchInRadioButton(String label) {
    JRadioButton button = new JRadioButton(label, false);
    button.setActionCommand(label);
    searchIn.add(button);
    return button;
  }

  private JPanel initSearchFields() {
    JPanel p = new JPanel();
    p.setLayout(new GridLayout(6, 1, 5, 2));
    p.add(new JLabel("Search In: "));

    JRadioButton all = new JRadioButton("All", true);
    all.setActionCommand("All");
    searchIn.add(all);
    p.add(all);

    p.add(this.makeSearchInRadioButton("Name"));
    p.add(this.makeSearchInRadioButton("Mailbox"));
    p.add(this.makeSearchInRadioButton("Handle"));

    return p;
  }
  
  private JPanel initServerChoice() {
    final JPanel p = new JPanel();
    p.setLayout(new GridLayout(6, 1, 5, 2));
    p.add(new JLabel("Search At: "));

    chosenServer.setText(server.getHost().getHostName());
    p.add(chosenServer);
    chosenServer.addActionListener( new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent event) { 
        try {
          server = new WhoisQuery(chosenServer.getText());
        } catch (UnknownHostException ex) {
           JOptionPane.showMessageDialog(p, 
             ex.getMessage(), "Alert", JOptionPane.ERROR_MESSAGE);
        }
      }
    } );
    
    return p;
  }

  private class LookupNames implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent event) {
      names.setText("");
      SwingWorker<String, Object> worker = new Lookup();
      worker.execute();
    }
  }
  
  private class Lookup extends SwingWorker<String, Object> {

    @Override
    protected String doInBackground() throws Exception {
      WhoisQuery.SearchIn group = WhoisQuery.SearchIn.ALL;
      WhoisQuery.SearchFor category = WhoisQuery.SearchFor.ANY;
      
      String searchForLabel = searchFor.getSelection().getActionCommand();
      String searchInLabel = searchIn.getSelection().getActionCommand();
      
      if (searchInLabel.equals("Name")) group = WhoisQuery.SearchIn.NAME; 
      else if (searchInLabel.equals("Mailbox")) {
        group = WhoisQuery.SearchIn.MAILBOX;
      } else if (searchInLabel.equals("Handle")) {
        group = WhoisQuery.SearchIn.HANDLE;
      }

      if (searchForLabel.equals("Network")) {
        category = WhoisQuery.SearchFor.NETWORK;
      } else if (searchForLabel.equals("Person")) {
        category = WhoisQuery.SearchFor.PERSON;
      } else if (searchForLabel.equals("Host")) {
        category = WhoisQuery.SearchFor.HOST;
      } else if (searchForLabel.equals("Domain")) {
        category = WhoisQuery.SearchFor.DOMAIN;
      } else if (searchForLabel.equals("Organization")) {
        category = WhoisQuery.SearchFor.ORGANIZATION;
      } else if (searchForLabel.equals("Group")) {
        category = WhoisQuery.SearchFor.GROUP;
      } else if (searchForLabel.equals("Gateway")) {
        category = WhoisQuery.SearchFor.GATEWAY;
      } else if (searchForLabel.equals("ASN")) {
        category = WhoisQuery.SearchFor.ASN;
      }

      server.setHost(chosenServer.getText());
      return server.lookUpNames(searchString.getText(), 
         category, group, exactMatch.isSelected());
    }
    
    @Override
    protected void done() {
      try { 
        names.setText(get());
      } catch (Exception ex) {
        JOptionPane.showMessageDialog(WhoisGUI.this, 
            ex.getMessage(), "Lookup Failed", JOptionPane.ERROR_MESSAGE);
      }
    }
  }

  public static void main(String[] args) {
    try {
      WhoisQuery server = new WhoisQuery();
      WhoisGUI a = new WhoisGUI(server);
      a.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
      a.pack();
      EventQueue.invokeLater(new FrameShower(a));
    } catch (UnknownHostException ex) {
      JOptionPane.showMessageDialog(null, "Could not locate default host "
          + WhoisQuery.DEFAULT_HOST, "Error", JOptionPane.ERROR_MESSAGE);    
    }
  }

  private static class FrameShower implements Runnable {
  
    private final Frame frame;
    
    FrameShower(Frame frame) {
      this.frame = frame;
    }
    
    @Override
    public void run() {
     frame.setVisible(true);
    } 
  }
}