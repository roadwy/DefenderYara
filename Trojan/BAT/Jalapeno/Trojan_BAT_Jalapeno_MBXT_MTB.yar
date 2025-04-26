
rule Trojan_BAT_Jalapeno_MBXT_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 31 37 44 31 35 00 34 35 42 37 37 43 31 38 00 46 30 33 46 35 30 } //2 ㄲ䐷㔱㐀䈵㜷ㅃ8う䘳〵
		$a_01_1 = {31 36 42 37 43 33 39 41 2e 72 65 73 6f 75 72 63 65 73 } //1 16B7C39A.resources
		$a_01_2 = {75 6e 6b 6e 6f 77 6e 73 70 66 5f 6c 6f 61 64 65 72 } //1 unknownspf_loader
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}