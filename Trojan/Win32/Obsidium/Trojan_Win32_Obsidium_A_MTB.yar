
rule Trojan_Win32_Obsidium_A_MTB{
	meta:
		description = "Trojan:Win32/Obsidium.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {36 dc 71 5b eb 03 d2 a5 00 eb 05 32 ae 3f 9b 0a b8 0e 48 3c f7 eb 01 76 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}