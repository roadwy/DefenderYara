
rule Trojan_Win32_AveMaria_MS_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c0 01 89 45 ?? 8b 4d 8c 83 e9 01 39 4d ?? 7f 33 8b 55 8c 83 ea 01 2b 55 ?? 8b 85 [0-04] 8b 0c ?? f7 d1 89 8d [0-04] 83 bd [0-05] 74 0e 8b 55 84 03 55 ?? 8a 85 [0-04] 88 02 eb b9 } //1
		$a_02_1 = {83 c2 01 89 [0-02] 8b [0-02] 3b [0-05] 7d ?? 8b [0-02] 99 f7 [0-05] 89 [0-05] 8b [0-02] 03 [0-02] 0f [0-04] 8b [0-05] 0f [0-04] 33 ?? 8b [0-02] 03 [0-02] 88 10 eb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}