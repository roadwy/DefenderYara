
rule Trojan_Win32_Ursnif_MBXV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 61 62 34 32 39 6b 6f 32 37 2e 64 6c 6c 00 48 65 6a 61 63 38 35 54 00 56 69 73 69 62 6c 65 45 6e 74 72 79 00 58 50 4f 75 51 33 36 } //1 慲㑢㤲潫㜲搮汬䠀橥捡㔸T楖楳汢䕥瑮祲堀佐兵㘳
	condition:
		((#a_01_0  & 1)*1) >=1
 
}