
rule Trojan_Win32_Zusy_RDD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 1f 8b 55 ec 8b 5d d4 32 0c 1a 8b 55 e8 88 0c 1a 81 c3 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}