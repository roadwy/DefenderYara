
rule Trojan_BAT_Shelm_ASH_MTB{
	meta:
		description = "Trojan:BAT/Shelm.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 16 2b 0f 07 11 16 07 11 16 91 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 ea } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}