
rule Backdoor_Win32_Duetag_A{
	meta:
		description = "Backdoor:Win32/Duetag.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 65 74 70 2e 6a 75 6a 75 74 61 6e 67 2e 63 6f 6d } //1 http://getp.jujutang.com
		$a_01_1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 3b 20 2e 4e 45 54 34 2e 30 43 3b 20 2e 4e 45 54 34 2e 30 45 } //1 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;.NET CLR 2.0.50727; .NET4.0C; .NET4.0E
		$a_01_2 = {63 63 2e 74 6d 70 } //1 cc.tmp
		$a_01_3 = {6d 5f 70 54 63 70 41 63 63 65 70 74 43 6f 6e } //1 m_pTcpAcceptCon
		$a_01_4 = {25 73 5c 63 6f 6e 66 69 67 2e 64 61 74 } //1 %s\config.dat
		$a_01_5 = {00 55 64 70 53 65 6e 64 3a 00 } //1 唀灤敓摮:
		$a_01_6 = {00 44 6f 43 6c 69 65 6e 74 54 61 73 6b 00 } //1 䐀䍯楬湥呴獡k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}