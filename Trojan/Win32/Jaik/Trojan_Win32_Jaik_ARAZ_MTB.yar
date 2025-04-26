
rule Trojan_Win32_Jaik_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Jaik.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 16 30 04 0b 83 c1 01 39 cd 75 e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}