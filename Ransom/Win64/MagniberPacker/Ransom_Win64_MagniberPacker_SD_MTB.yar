
rule Ransom_Win64_MagniberPacker_SD_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 ae a0 0d 00 00 e9 ?? ?? ?? ?? a0 ?? ?? ?? ?? ?? ?? ?? ?? 96 bc ?? ?? ?? ?? d2 eb 76 ?? 7a ?? 94 e5 ?? eb ?? 05 aa 48 81 fa 94 01 01 00 eb e9 ?? ?? ?? ?? a2 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}