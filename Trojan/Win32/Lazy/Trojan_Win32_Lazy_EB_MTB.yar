
rule Trojan_Win32_Lazy_EB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 77 78 75 6e 69 7a } //1 awxuniz
		$a_01_1 = {77 6a 67 75 63 74 68 70 7a } //1 wjgucthpz
		$a_01_2 = {63 6d 65 79 6c 64 70 77 75 6a 68 } //1 cmeyldpwujh
		$a_01_3 = {63 62 66 6b 69 65 6c 76 71 74 } //1 cbfkielvqt
		$a_01_4 = {79 6b 67 70 68 6c 6f 72 6d 62 } //1 ykgphlormb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Lazy_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 6b 63 70 75 64 73 72 79 } //1 mokcpudsry
		$a_01_1 = {6c 75 78 76 69 6e 70 7a 66 62 65 6a } //1 luxvinpzfbej
		$a_01_2 = {6e 6f 64 77 63 78 6a 79 70 74 69 61 } //1 nodwcxjyptia
		$a_01_3 = {6e 76 73 6d 6c 74 6b 61 64 71 79 69 } //1 nvsmltkadqyi
		$a_01_4 = {71 63 62 67 74 77 78 66 6d 64 6e 70 } //1 qcbgtwxfmdnp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}