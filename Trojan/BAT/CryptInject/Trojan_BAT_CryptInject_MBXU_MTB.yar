
rule Trojan_BAT_CryptInject_MBXU_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {38 38 61 64 32 66 64 37 63 65 37 61 61 66 38 37 62 62 62 37 38 31 00 63 61 66 30 33 63 62 36 35 63 32 37 35 63 38 } //2 㠸摡昲㝤散愷晡㜸扢㝢ㄸ挀晡㌰扣㔶㉣㔷㡣
		$a_01_1 = {32 38 30 33 66 66 39 62 34 33 61 35 36 65 37 36 35 35 00 63 37 63 66 31 30 61 62 38 64 64 33 62 36 65 30 39 65 } //2
		$a_01_2 = {50 72 6f 44 52 45 4e 41 4c 49 4e } //1 ProDRENALIN
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}