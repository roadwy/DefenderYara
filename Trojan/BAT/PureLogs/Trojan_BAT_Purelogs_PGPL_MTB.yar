
rule Trojan_BAT_Purelogs_PGPL_MTB{
	meta:
		description = "Trojan:BAT/Purelogs.PGPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 f8 e8 3f 6c 82 c9 4e 41 7a 2d 7f 91 7a b4 5b 1f fb 4b c6 71 18 d6 bb b8 90 9c 0f fb 51 d4 55 ea 83 14 2a 6f 85 cb 21 94 d6 95 ea 59 a5 28 f1 67 6e b0 1b 54 35 41 da 46 8f 50 bf 02 6e 5d 6f 0a 2a 87 e7 10 f9 2e d6 f7 5e ee a2 3b 29 34 30 c2 7e 73 54 be 10 ed 79 39 c6 64 44 6a 47 18 93 05 e6 8b ef 2f da } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}