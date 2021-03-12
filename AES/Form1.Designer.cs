
namespace AES
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.encryptButton = new System.Windows.Forms.Button();
            this.label4 = new System.Windows.Forms.Label();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.decryptButton = new System.Windows.Forms.Button();
            this.keyTextBox = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.fileSelectButton = new System.Windows.Forms.Button();
            this.label3 = new System.Windows.Forms.Label();
            this.encypherTexBox = new System.Windows.Forms.TextBox();
            this.radioButton1 = new System.Windows.Forms.RadioButton();
            this.radioButton2 = new System.Windows.Forms.RadioButton();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.decypherResult = new System.Windows.Forms.Label();
            this.filePathLabel = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.textInFileLabel = new System.Windows.Forms.Label();
            this.newFileNameTexBox = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.groupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // encryptButton
            // 
            this.encryptButton.Location = new System.Drawing.Point(426, 363);
            this.encryptButton.Name = "encryptButton";
            this.encryptButton.Size = new System.Drawing.Size(75, 23);
            this.encryptButton.TabIndex = 3;
            this.encryptButton.Text = "Encrypt";
            this.encryptButton.UseVisualStyleBackColor = true;
            this.encryptButton.Click += new System.EventHandler(this.encryptButton_Click);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(252, 68);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(29, 15);
            this.label4.TabIndex = 7;
            this.label4.Text = "Key:";
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // decryptButton
            // 
            this.decryptButton.Location = new System.Drawing.Point(43, 363);
            this.decryptButton.Name = "decryptButton";
            this.decryptButton.Size = new System.Drawing.Size(75, 23);
            this.decryptButton.TabIndex = 2;
            this.decryptButton.Text = "Decrypt";
            this.decryptButton.UseVisualStyleBackColor = true;
            this.decryptButton.Click += new System.EventHandler(this.decryptButton_Click);
            // 
            // keyTextBox
            // 
            this.keyTextBox.Location = new System.Drawing.Point(134, 86);
            this.keyTextBox.Name = "keyTextBox";
            this.keyTextBox.Size = new System.Drawing.Size(282, 23);
            this.keyTextBox.TabIndex = 8;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 260);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(92, 15);
            this.label1.TabIndex = 11;
            this.label1.Text = "Decypher result:";
            // 
            // label2
            // 
            this.label2.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)));
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(209, 9);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(133, 15);
            this.label2.TabIndex = 12;
            this.label2.Text = "AES decypher/encypher";
            this.label2.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            // 
            // fileSelectButton
            // 
            this.fileSelectButton.Location = new System.Drawing.Point(234, 27);
            this.fileSelectButton.Name = "fileSelectButton";
            this.fileSelectButton.Size = new System.Drawing.Size(75, 23);
            this.fileSelectButton.TabIndex = 13;
            this.fileSelectButton.Text = "Select file";
            this.fileSelectButton.UseVisualStyleBackColor = true;
            this.fileSelectButton.Click += new System.EventHandler(this.fileSelectButton_Click);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(310, 260);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(82, 15);
            this.label3.TabIndex = 14;
            this.label3.Text = "Encypher text:";
            // 
            // encypherTexBox
            // 
            this.encypherTexBox.Location = new System.Drawing.Point(310, 289);
            this.encypherTexBox.Name = "encypherTexBox";
            this.encypherTexBox.Size = new System.Drawing.Size(262, 23);
            this.encypherTexBox.TabIndex = 15;
            // 
            // radioButton1
            // 
            this.radioButton1.AutoSize = true;
            this.radioButton1.Checked = true;
            this.radioButton1.Location = new System.Drawing.Point(6, 22);
            this.radioButton1.Name = "radioButton1";
            this.radioButton1.Size = new System.Drawing.Size(48, 19);
            this.radioButton1.TabIndex = 18;
            this.radioButton1.TabStop = true;
            this.radioButton1.Text = "CBC";
            this.radioButton1.UseVisualStyleBackColor = true;
            // 
            // radioButton2
            // 
            this.radioButton2.AutoSize = true;
            this.radioButton2.Location = new System.Drawing.Point(6, 47);
            this.radioButton2.Name = "radioButton2";
            this.radioButton2.Size = new System.Drawing.Size(46, 19);
            this.radioButton2.TabIndex = 19;
            this.radioButton2.Text = "ECB";
            this.radioButton2.UseVisualStyleBackColor = true;
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.radioButton1);
            this.groupBox1.Controls.Add(this.radioButton2);
            this.groupBox1.Location = new System.Drawing.Point(209, 115);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(131, 79);
            this.groupBox1.TabIndex = 20;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Block cipher mode";
            // 
            // decypherResult
            // 
            this.decypherResult.AutoSize = true;
            this.decypherResult.Location = new System.Drawing.Point(12, 289);
            this.decypherResult.Name = "decypherResult";
            this.decypherResult.Size = new System.Drawing.Size(147, 15);
            this.decypherResult.TabIndex = 21;
            this.decypherResult.Text = "----------------------------";
            // 
            // filePathLabel
            // 
            this.filePathLabel.AutoSize = true;
            this.filePathLabel.Location = new System.Drawing.Point(242, 53);
            this.filePathLabel.Name = "filePathLabel";
            this.filePathLabel.Size = new System.Drawing.Size(52, 15);
            this.filePathLabel.TabIndex = 22;
            this.filePathLabel.Text = "File path";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(12, 197);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(63, 15);
            this.label5.TabIndex = 23;
            this.label5.Text = "Text in file:";
            // 
            // textInFileLabel
            // 
            this.textInFileLabel.AutoSize = true;
            this.textInFileLabel.Location = new System.Drawing.Point(12, 227);
            this.textInFileLabel.Name = "textInFileLabel";
            this.textInFileLabel.Size = new System.Drawing.Size(28, 15);
            this.textInFileLabel.TabIndex = 24;
            this.textInFileLabel.Text = "Text";
            // 
            // newFileNameTexBox
            // 
            this.newFileNameTexBox.Location = new System.Drawing.Point(310, 219);
            this.newFileNameTexBox.Name = "newFileNameTexBox";
            this.newFileNameTexBox.Size = new System.Drawing.Size(262, 23);
            this.newFileNameTexBox.TabIndex = 25;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(310, 197);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(58, 15);
            this.label6.TabIndex = 26;
            this.label6.Text = "File name";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(584, 427);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.newFileNameTexBox);
            this.Controls.Add(this.textInFileLabel);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.filePathLabel);
            this.Controls.Add(this.decypherResult);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.encypherTexBox);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.fileSelectButton);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.keyTextBox);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.encryptButton);
            this.Controls.Add(this.decryptButton);
            this.Name = "Form1";
            this.Text = "Form1";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button encryptButton;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Button decryptButton;
        private System.Windows.Forms.TextBox keyTextBox;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button fileSelectButton;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox encypherTexBox;
        private System.Windows.Forms.RadioButton radioButton1;
        private System.Windows.Forms.RadioButton radioButton2;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Label decypherResult;
        private System.Windows.Forms.Label filePathLabel;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label textInFileLabel;
        private System.Windows.Forms.TextBox newFileNameTexBox;
        private System.Windows.Forms.Label label6;
    }
}

