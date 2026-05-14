
rule Trojan_Win32_Rhadamanthys_GMH_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 00 40 ff ff ff ff 20 b5 d5 00 70 b5 d5 00 10 3a 3a 01 1c 3a 3a 01 28 3a 3a 01 30 3a 3a 01 f0 b5 d5 00 ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}