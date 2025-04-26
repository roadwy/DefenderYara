
rule Trojan_Win32_Gamaredon_psyH_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 07 47 08 c0 74 dc 89 f9 79 07 0f b7 07 47 50 47 b9 57 48 f2 ae 55 ff 96 e8 cb 01 00 09 c0 74 07 89 03 83 c3 04 eb d8 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}