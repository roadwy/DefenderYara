
rule TrojanProxy_BAT_Mictanort_A{
	meta:
		description = "TrojanProxy:BAT/Mictanort.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 4e 59 59 72 72 2e 52 65 73 6f 75 72 63 65 73 2e 6d 61 6b 65 63 65 72 74 2e 65 78 65 } //01 00  NNYYrr.Resources.makecert.exe
		$a_01_1 = {46 69 64 64 6c 65 72 2e 66 72 6d 50 72 6f 6d 70 74 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Fiddler.frmPrompt.resources
		$a_01_2 = {54 61 6d 69 72 2e 53 68 61 72 70 53 73 68 2e 6a 73 63 68 2e 65 78 61 6d 70 6c 65 73 2e 49 6e 70 75 74 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Tamir.SharpSsh.jsch.examples.InputForm.resources
		$a_01_3 = {09 4d 69 63 72 6f 20 4e 65 74 } //00 00  䴉捩潲丠瑥
	condition:
		any of ($a_*)
 
}