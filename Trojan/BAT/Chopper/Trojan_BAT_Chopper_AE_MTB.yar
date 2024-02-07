
rule Trojan_BAT_Chopper_AE_MTB{
	meta:
		description = "Trojan:BAT/Chopper.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 65 73 70 6f 6e 73 65 2e 57 72 69 74 65 28 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 } //01 00  Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c
		$a_01_1 = {4a 53 63 72 69 70 74 45 76 61 6c 75 61 74 65 } //00 00  JScriptEvaluate
	condition:
		any of ($a_*)
 
}