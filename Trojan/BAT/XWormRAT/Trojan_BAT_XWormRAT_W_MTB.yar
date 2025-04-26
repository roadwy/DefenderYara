
rule Trojan_BAT_XWormRAT_W_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 1a 5d 91 07 1a 5d 1e 5a 1f ?? 5f 63 d2 61 d2 52 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}