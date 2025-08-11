
rule Trojan_BAT_CoinMiner_MCF_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 49 37 58 65 73 37 64 63 52 4f 56 30 37 58 64 32 54 57 00 44 53 51 73 74 58 37 4c 68 6a 67 44 49 54 5a 59 76 4e 38 00 71 32 4a 30 52 72 37 62 } //1 䥤堷獥搷剣噏㜰摘吲W卄獑塴䰷橨䑧呉奚乶8㉱お牒户
	condition:
		((#a_01_0  & 1)*1) >=1
 
}