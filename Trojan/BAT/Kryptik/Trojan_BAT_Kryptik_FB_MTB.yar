
rule Trojan_BAT_Kryptik_FB_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 11 05 11 0c 28 [0-10] 13 0e 02 11 0d 11 0e 28 [0-04] 13 0f 11 0f 13 10 11 10 2c 2c 09 19 8d [0-04] 25 16 12 0d 28 [0-04] 9c 25 17 12 0d 28 [0-04] 9c 25 18 12 0d 28 [0-0d] 11 0c 17 d6 13 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}