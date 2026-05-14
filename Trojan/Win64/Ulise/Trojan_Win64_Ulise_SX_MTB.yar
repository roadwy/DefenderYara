
rule Trojan_Win64_Ulise_SX_MTB{
	meta:
		description = "Trojan:Win64/Ulise.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8d 4c 24 ?? ff d3 48 8b 9c 24 ?? ?? ?? ?? b8 01 00 00 00 99 f7 ff 48 8b bc 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 48 33 cc e8 } //10
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 75 70 64 61 74 65 2d 73 79 73 74 61 73 6b 22 20 2f 74 72 20 22 5c 22 63 6d 64 2e 65 78 65 5c 22 20 5c 22 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 } //40 schtasks /create /tn "update-systask" /tr "\"cmd.exe\" \"/c powershell -EncodedCommand
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*40) >=50
 
}