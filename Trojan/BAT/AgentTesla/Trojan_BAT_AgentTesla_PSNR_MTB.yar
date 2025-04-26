
rule Trojan_BAT_AgentTesla_PSNR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 40 00 00 06 0a 06 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 25 26 07 16 07 8e 69 6f ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 25 26 06 6f ?? ?? ?? 0a 0c 1f 61 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}