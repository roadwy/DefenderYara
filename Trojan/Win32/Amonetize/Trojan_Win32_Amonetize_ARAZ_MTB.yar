
rule Trojan_Win32_Amonetize_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Amonetize.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e2 d1 ea 8d 04 52 8b d1 2b d0 0f b6 44 15 fe 32 44 0f 02 83 c1 03 88 46 02 83 c6 03 83 f9 1b 7c 95 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}