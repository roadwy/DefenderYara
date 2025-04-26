
rule Trojan_BAT_AsyncRAT_I_MSR{
	meta:
		description = "Trojan:BAT/AsyncRAT.I!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {31 38 38 2e 32 32 37 2e 35 37 2e 34 36 2f 66 6f 6c 64 65 72 2f 63 6f 72 65 5f 48 76 6f 76 74 68 7a 6e 2e 6a 70 67 } //188.227.57.46/folder/core_Hvovthzn.jpg  1
		$a_80_1 = {48 61 64 67 62 62 70 69 2e 54 79 6e 77 70 66 67 64 71 71 7a 76 69 65 } //Hadgbbpi.Tynwpfgdqqzvie  1
		$a_80_2 = {53 74 61 72 74 2d 53 6c 65 65 70 20 2d 53 65 63 6f 6e 64 73 20 33 30 } //Start-Sleep -Seconds 30  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}