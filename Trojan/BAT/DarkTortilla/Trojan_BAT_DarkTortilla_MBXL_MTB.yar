
rule Trojan_BAT_DarkTortilla_MBXL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MBXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {35 37 65 39 39 39 66 66 33 64 31 7d 00 3c 4d 6f 64 75 6c 65 3e 00 6f 70 69 6b 6a 66 6d 6e 63 78 63 7a 33 64 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 㜵㥥㤹晦搳紱㰀潍畤敬>灯歩晪湭硣穣搳刮獥畯捲獥爮獥畯捲獥
	condition:
		((#a_01_0  & 1)*1) >=1
 
}