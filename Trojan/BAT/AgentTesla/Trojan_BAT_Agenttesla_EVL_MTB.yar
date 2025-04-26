
rule Trojan_BAT_Agenttesla_EVL_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.EVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 12 01 11 04 11 05 28 ?? ?? ?? 06 00 00 11 05 16 fe 02 13 06 11 06 2d d8 } //1
		$a_01_1 = {53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 53 00 65 00 63 00 6f 00 6e 00 64 00 73 00 20 00 39 00 3b 00 53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 53 00 65 00 63 00 6f 00 6e 00 64 00 73 00 20 00 39 00 3b 00 } //1 Start-Sleep -Seconds 9;Start-Sleep -Seconds 9;
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}