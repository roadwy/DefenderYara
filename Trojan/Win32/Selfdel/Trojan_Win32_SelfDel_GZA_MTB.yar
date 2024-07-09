
rule Trojan_Win32_SelfDel_GZA_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.GZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 3b 4a 18 7d ?? 8b 5d fc 8b 1c 8b 03 5d 08 ff 75 0c 53 e8 ?? ?? ?? ?? 83 f8 01 74 03 41 eb ?? 8b 45 f8 8b 40 24 03 45 08 31 db 66 8b 1c 48 8b 45 f8 8b 40 1c 03 45 08 8b 04 98 03 45 08 } //10
		$a_01_1 = {6f 70 65 6e 20 73 74 61 74 75 73 20 64 3a 5c 5c 65 64 77 72 5c 61 72 61 66 } //1 open status d:\\edwr\araf
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}