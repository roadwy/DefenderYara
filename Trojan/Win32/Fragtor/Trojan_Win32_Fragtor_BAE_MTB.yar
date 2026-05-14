
rule Trojan_Win32_Fragtor_BAE_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 8d 4c 24 20 03 ce 8d 04 0b 99 f7 7c 24 10 32 11 88 14 37 46 83 fe 0d 7c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}