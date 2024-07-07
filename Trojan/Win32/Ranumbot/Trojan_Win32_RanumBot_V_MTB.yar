
rule Trojan_Win32_RanumBot_V_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 2d 57 77 5f 34 71 76 57 68 50 4a 75 38 45 61 37 47 31 6e 66 2f 42 73 7a 59 76 75 68 56 69 41 65 30 31 59 4e 76 4d 56 54 6e 2f 76 49 48 6b 72 33 31 65 59 53 43 44 59 33 49 57 4c 47 72 49 2f 72 32 5f 57 59 62 33 67 51 30 6e 62 30 37 48 50 63 55 63 37 } //1 Go build ID: "-Ww_4qvWhPJu8Ea7G1nf/BszYvuhViAe01YNvMVTn/vIHkr31eYSCDY3IWLGrI/r2_WYb3gQ0nb07HPcUc7
	condition:
		((#a_01_0  & 1)*1) >=1
 
}