
rule Trojan_BAT_Filecoder_PSOW_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.PSOW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 53 34 00 70 28 ?? ?? ?? 0a 26 72 71 34 00 70 72 87 34 00 70 28 ?? ?? ?? 0a 26 72 91 34 00 70 72 87 34 00 70 28 ?? ?? ?? 0a 26 72 ab 34 00 70 72 bf 34 00 70 28 ?? ?? ?? 0a 26 72 cb 34 00 70 72 db 34 00 70 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}