
rule Trojan_BAT_Chopper_AB_MTB{
	meta:
		description = "Trojan:BAT/Chopper.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 6e 6c 74 65 73 74 20 2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 20 2f 61 6c 6c 5f 74 72 75 73 74 73 22 29 2e 53 74 64 4f 75 74 2e 52 65 61 64 41 6c 6c 28 29 29 3b } //01 00  Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c nltest /domain_trusts /all_trusts").StdOut.ReadAll());
		$a_81_1 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 79 73 74 65 6d 69 6e 66 6f 22 29 2e 53 74 64 4f 75 74 2e 52 65 61 64 41 6c 6c 28 29 29 3b } //02 00  Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c systeminfo").StdOut.ReadAll());
		$a_81_2 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c 22 29 2e 53 74 64 4f 75 74 2e 52 65 61 64 41 6c 6c 28 29 29 3b } //00 00  Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c ipconfig /all").StdOut.ReadAll());
	condition:
		any of ($a_*)
 
}