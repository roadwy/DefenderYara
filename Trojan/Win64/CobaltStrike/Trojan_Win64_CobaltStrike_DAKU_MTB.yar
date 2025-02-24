
rule Trojan_Win64_CobaltStrike_DAKU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DAKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 89 85 a4 02 00 00 48 63 85 c4 02 00 00 48 63 8d a4 02 00 00 0f b6 4c 0d 10 48 8b 95 80 04 00 00 0f b6 04 02 33 c1 48 63 8d c4 02 00 00 48 8b 95 80 04 00 00 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}