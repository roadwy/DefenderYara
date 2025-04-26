
rule Trojan_BAT_LummaStealer_CCCR_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 61 45 48 56 4f 68 55 45 56 71 72 77 71 76 6a 48 49 75 } //1 jaEHVOhUEVqrwqvjHIu
		$a_01_1 = {6a 68 6a 51 42 72 68 57 54 71 45 4f 6e 53 76 74 78 38 6e } //1 jhjQBrhWTqEOnSvtx8n
		$a_01_2 = {59 4a 6f 6f 54 69 68 46 64 79 62 54 39 68 51 49 6b 6e 6d } //1 YJooTihFdybT9hQIknm
		$a_01_3 = {57 34 4a 36 31 71 68 66 38 47 52 45 43 46 70 6c 39 37 75 } //1 W4J61qhf8GRECFpl97u
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}