
rule Backdoor_Win32_Drixed_Q{
	meta:
		description = "Backdoor:Win32/Drixed.Q,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {ba 9d 3a a3 9c b9 87 c2 cc 0c e8 } //1
		$a_01_1 = {ba cd df 66 92 b9 87 c2 cc 0c e8 } //1
		$a_01_2 = {ba 60 86 f7 a7 b9 2a 9f e2 75 e8 } //1
		$a_01_3 = {ba f0 ff 84 bc b9 2a 9f e2 75 e8 } //1
		$a_01_4 = {ba 5d 6c d0 60 b9 2a 9f e2 75 e8 } //1
		$a_01_5 = {ba 59 65 1d ad b9 2a 9f e2 75 e8 } //1
		$a_01_6 = {ba c6 0c 71 2d b9 2a 9f e2 75 e8 } //1
		$a_01_7 = {ba c9 e9 34 2b b9 f2 4f ed f4 e8 } //1
		$a_01_8 = {bf b1 f6 38 f8 bb f2 4f ed f4 } //1
		$a_01_9 = {64 6c 6c 20 6c 6f 61 64 65 64 2c 20 72 75 6e 3f } //1 dll loaded, run?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}