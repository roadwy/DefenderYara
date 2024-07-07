
rule Trojan_Win32_DllInject_SPQ_MTB{
	meta:
		description = "Trojan:Win32/DllInject.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 6f 73 67 68 6f 73 72 64 6a 41 6a 73 72 6a 69 72 68 72 } //1 BosghosrdjAjsrjirhr
		$a_81_1 = {4c 6f 73 68 67 73 72 69 6a 41 6a 6f 73 6a 68 67 69 65 } //1 LoshgsrijAjosjhgie
		$a_81_2 = {4e 73 6a 67 6f 73 6a 41 6a 6f 73 6a 67 68 65 6a 68 67 } //1 NsjgosjAjosjghejhg
		$a_81_3 = {50 73 6a 6f 67 6f 73 72 41 6a 6f 73 6a 72 68 69 72 73 6a } //1 PsjogosrAjosjrhirsj
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}