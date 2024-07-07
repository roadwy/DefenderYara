
rule Trojan_Win32_Glupteba_GMH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 ff 01 ea 31 38 89 db 01 c9 81 c0 04 00 00 00 bb 90 01 04 39 d0 75 90 01 01 89 ce c3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}