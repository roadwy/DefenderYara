
rule Ransom_Win32_Basta_SIH_MTB{
	meta:
		description = "Ransom:Win32/Basta.SIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 68 79 39 36 38 6a 78 33 2e 64 6c 6c } //1 phy968jx3.dll
		$a_01_1 = {35 02 14 03 00 89 81 c0 00 00 00 a1 8c dc 0f 10 8b 4e 58 8b d3 c1 ea 08 88 14 08 ff 46 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}