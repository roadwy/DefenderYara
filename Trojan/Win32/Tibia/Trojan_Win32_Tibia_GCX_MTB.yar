
rule Trojan_Win32_Tibia_GCX_MTB{
	meta:
		description = "Trojan:Win32/Tibia.GCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 5c 30 ff 8d 45 e8 33 d2 8a d3 8b 4d f0 33 d1 e8 ?? ?? ?? ?? 8b 55 e8 8d 45 ec e8 ?? ?? ?? ?? 46 4f 75 } //10
		$a_01_1 = {5c 44 72 69 76 65 72 73 5c 45 74 63 5c 48 6f 73 74 73 } //1 \Drivers\Etc\Hosts
		$a_01_2 = {74 69 62 69 61 63 6c 69 65 6e 74 } //1 tibiaclient
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}