
rule Trojan_Win32_Neoreblamy_GJH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 71 62 76 76 6c 6d 20 73 63 63 74 75 69 6d 68 20 79 62 71 68 6f 78 20 6a 61 62 74 20 66 68 6a 70 6f 6d 78 6b 20 72 63 68 20 79 6a 6a 65 20 71 65 6b 64 20 68 62 77 66 63 20 69 6e 65 79 79 } //01 00  yqbvvlm scctuimh ybqhox jabt fhjpomxk rch yjje qekd hbwfc ineyy
		$a_01_1 = {61 6f 76 62 63 20 65 6d 75 20 74 70 73 20 63 6c 64 72 20 74 6d 70 68 62 78 63 } //01 00  aovbc emu tps cldr tmphbxc
		$a_01_2 = {78 62 69 73 76 20 64 6c 72 62 6c 70 6f 6d 69 20 63 72 76 6e 71 71 6e 78 79 20 68 70 6a } //01 00  xbisv dlrblpomi crvnqqnxy hpj
		$a_01_3 = {63 68 6f 65 6a 20 61 62 6a 64 6e 20 78 6e 70 20 6f 62 71 6a 73 71 20 79 70 64 20 62 6d 69 68 6a 78 67 78 76 } //00 00  choej abjdn xnp obqjsq ypd bmihjxgxv
	condition:
		any of ($a_*)
 
}