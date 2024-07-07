
rule Trojan_Win64_DanaBot_SA_MTB{
	meta:
		description = "Trojan:Win64/DanaBot.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 0f b6 00 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 0f af 45 90 01 01 0f af 45 90 01 01 8b 4d 90 01 01 03 c8 33 4d 90 01 01 89 4d 90 01 01 83 45 90 01 02 83 eb 90 01 01 85 db 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}