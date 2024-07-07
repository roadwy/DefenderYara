
rule Trojan_Win64_CobaltStrike_IRH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 cf 48 89 d9 48 89 c3 48 8d 44 24 48 e8 ba 80 fa ff 48 8d 44 24 48 31 db 31 c9 48 89 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}