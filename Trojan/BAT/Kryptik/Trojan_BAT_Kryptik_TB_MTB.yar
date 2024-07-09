
rule Trojan_BAT_Kryptik_TB_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 06 07 06 8e 69 6a 5d 28 [0-04] 28 [0-04] 91 61 02 07 17 6a 58 20 [0-04] 6a 5d 28 [0-09] 91 59 6a 20 [0-04] 6a 58 20 [0-04] 6a 5d d2 9c ?? 07 17 6a 58 0b 07 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}