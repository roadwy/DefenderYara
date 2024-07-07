
rule Trojan_Win32_Obsidium_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Obsidium.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 5a c2 00 ba 11 a9 fe 2b 47 e9 8e d5 86 64 33 18 91 52 44 6a 52 dd 86 92 8a 8a 49 d7 a2 92 74 80 ba 34 25 b4 21 5a fb 12 d3 ea 56 09 64 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}