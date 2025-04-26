
rule Trojan_Win64_Rootkit_GZT_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4c 24 08 48 83 ec 38 48 8b 4c 24 40 ff 15 e7 47 01 00 48 89 44 24 20 48 83 7c 24 20 00 74 17 48 8b 54 24 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}