
rule Trojan_Win64_Havokiz_SB{
	meta:
		description = "Trojan:Win64/Havokiz.SB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {10 48 89 d9 48 8b 59 10 ff 61 08 0f 1f 40 00 49 89 cb c3 49 89 ca 41 8b 43 08 41 ff 23 c3 90 48 c1 e1 04 31 c0 81 e1 f0 0f 00 00 49 01 c8 4c 8d 0c 02 4e 8d 14 00 31 c9 45 8a 1c 0a 48 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}