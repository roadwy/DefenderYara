
rule Trojan_BAT_Fsysna_PSLB_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.PSLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 6e 00 00 0a fe 0c 00 00 20 02 00 00 00 9a 28 ?? ?? ?? 0a 25 fe 0c 00 00 20 01 00 00 00 9a 28 70 00 00 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 20 b8 94 a4 51 38 cb fd ff ff fe 0c 04 00 20 32 f6 2b 35 5a 20 45 29 60 68 61 38 b6 fd ff ff fe 0c 01 00 72 b5 06 00 70 28 58 00 00 06 20 20 00 00 00 14 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}