
rule Trojan_Win32_Trickbot_ASET_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.ASET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 18 33 c1 69 c0 95 e9 d1 5b 33 d8 89 45 0c 83 6d f4 01 89 5d fc 0f } //1
		$a_01_1 = {5a 38 31 78 62 79 75 41 75 61 } //1 Z81xbyuAua
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}