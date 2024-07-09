
rule Trojan_Win32_Emotet_DSX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 54 14 ?? 30 55 } //1
		$a_81_1 = {69 62 56 30 37 6b 38 4f 76 4c 49 63 33 43 43 39 74 51 41 54 6e 31 30 6e 7a 58 48 53 37 61 65 55 33 79 6a 55 50 36 68 6b 37 79 30 4f } //1 ibV07k8OvLIc3CC9tQATn10nzXHS7aeU3yjUP6hk7y0O
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}