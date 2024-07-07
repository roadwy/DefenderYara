
rule Trojan_Win32_Gepys_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Gepys.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 04 18 88 45 df 43 8b 45 ec 03 45 f0 8b 55 08 0f b6 4d df 31 f1 88 0c 02 8b 45 e8 09 f0 39 45 f0 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}