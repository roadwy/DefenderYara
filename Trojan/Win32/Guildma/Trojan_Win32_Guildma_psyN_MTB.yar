
rule Trojan_Win32_Guildma_psyN_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba de 00 00 00 8a 06 e9 00 00 00 00 32 c2 88 07 90 46 90 47 49 90 83 f9 00 90 0f 85 e5 ff ff ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}