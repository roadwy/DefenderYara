
rule Trojan_Win32_LokiBot_DP_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 6a 40 68 ?? ?? ?? ?? 8b 45 fc 50 e8 } //1
		$a_02_1 = {33 db 8b f3 8a [0-06] 80 f2 1b 03 75 fc 88 16 90 05 05 01 90 40 40 90 05 05 01 90 43 81 fb [0-02] 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}