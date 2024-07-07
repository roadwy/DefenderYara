
rule Trojan_Win32_BHO_DN{
	meta:
		description = "Trojan:Win32/BHO.DN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 45 48 70 72 2e 49 6e 76 6f 6b 65 2e 31 20 3d 20 73 20 27 49 6e 76 6f 6b 65 20 43 6c 61 73 73 27 } //1 IEHpr.Invoke.1 = s 'Invoke Class'
		$a_01_1 = {54 6a 6d 50 77 62 33 5f 47 66 65 62 76 6f 77 } //1 TjmPwb3_Gfebvow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}