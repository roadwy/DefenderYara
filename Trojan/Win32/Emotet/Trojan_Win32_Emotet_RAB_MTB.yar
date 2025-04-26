
rule Trojan_Win32_Emotet_RAB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 a2 18 00 00 f7 f9 83 c4 2c 45 0f b6 54 14 ?? 30 55 ?? 83 bc 24 ?? ?? ?? ?? 00 0f 85 } //1
		$a_81_1 = {78 70 5a 56 77 4f 45 59 30 79 71 6e 43 45 43 70 65 71 4a 73 48 66 46 41 46 36 45 63 6b 61 73 44 75 70 } //1 xpZVwOEY0yqnCECpeqJsHfFAF6EckasDup
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}