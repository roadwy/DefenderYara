
rule Trojan_Win32_Obsidium_AC_MTB{
	meta:
		description = "Trojan:Win32/Obsidium.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 c8 c9 3e b6 42 c6 1e dc 6b 7a e2 b9 e0 0e 89 04 c1 8e 6b 18 09 88 2c 86 ed 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}