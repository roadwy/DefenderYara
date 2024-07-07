
rule Spammer_Win32_Rlsloup_A{
	meta:
		description = "Spammer:Win32/Rlsloup.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 11 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 53 69 6d 70 6c 79 20 53 75 70 65 72 20 53 6f 66 74 77 61 72 65 5c 54 72 6f 6a 61 6e 20 52 65 6d 6f 76 65 72 5c } //65436 \Simply Super Software\Trojan Remover\
		$a_00_1 = {73 6d 74 70 2d 63 6c 69 65 6e 74 2d 72 6c 73 2e 64 6c 6c } //10 smtp-client-rls.dll
		$a_00_2 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c } //1 DeviceIoControl
		$a_00_3 = {44 65 6c 65 74 65 46 69 6c 65 41 } //1 DeleteFileA
		$a_00_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_00_5 = {43 6f 43 72 65 61 74 65 47 75 69 64 } //1 CoCreateGuid
		$a_00_6 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //1 FindFirstFileA
		$a_00_7 = {75 70 64 61 74 65 5f 6c 6f 61 64 } //1 update_load
		$a_00_8 = {47 65 74 4d 61 69 6c 73 6c 6f 74 49 6e 66 6f } //1 GetMailslotInfo
		$a_00_9 = {57 53 32 5f 33 32 2e 64 6c 6c } //1 WS2_32.dll
	condition:
		((#a_01_0  & 1)*65436+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=17
 
}
rule Spammer_Win32_Rlsloup_A_2{
	meta:
		description = "Spammer:Win32/Rlsloup.A,SIGNATURE_TYPE_PEHSTR,1a 00 16 00 17 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 } //2 netsh firewall delete allowedprogram "%s
		$a_01_1 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 } //2 netsh firewall add allowedprogram "%s
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 63 75 72 69 74 79 } //2 Software\Microsoft\Internet Explorer\Security
		$a_01_3 = {69 70 20 61 64 64 72 65 73 73 20 6c 69 6b 65 20 68 65 6c 6f } //2 ip address like helo
		$a_01_4 = {69 74 20 69 73 20 79 6f 75 20 61 67 61 69 6e 20 3a 2d 28 } //2 it is you again :-(
		$a_01_5 = {65 76 69 6c 5f 62 6f 75 6e 63 65 } //2 evil_bounce
		$a_01_6 = {2f 62 6e 2f 63 6f 6d 67 61 74 65 2e 78 68 74 6d 6c 3f } //2 /bn/comgate.xhtml?
		$a_01_7 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 25 73 } //1 Content-Type: %s
		$a_01_8 = {43 75 72 72 65 6e 74 20 49 50 20 41 64 64 72 65 73 73 3a } //1 Current IP Address:
		$a_01_9 = {48 6f 73 74 3a 20 63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //1 Host: checkip.dyndns.org
		$a_01_10 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 53 56 31 3b 20 2e 4e 45 54 } //1 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET
		$a_01_11 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //1 POST %s HTTP/1.1
		$a_01_12 = {64 61 74 61 3a 20 69 2f 6f 20 65 72 72 6f 72 } //1 data: i/o error
		$a_01_13 = {72 63 70 74 20 74 6f 3a 20 69 2f 6f 20 65 72 72 6f 72 } //1 rcpt to: i/o error
		$a_01_14 = {6d 61 69 6c 20 66 72 6f 6d 3a 20 69 2f 6f 20 65 72 72 6f 72 } //1 mail from: i/o error
		$a_01_15 = {4f 4b 2e 20 47 6f 74 20 25 64 20 69 70 73 } //1 OK. Got %d ips
		$a_01_16 = {45 6d 61 69 6c 3a 20 3c 25 73 3e } //1 Email: <%s>
		$a_01_17 = {53 65 73 73 69 6f 6e 20 73 74 61 72 74 65 64 20 28 76 3d 25 64 20 25 73 3b 20 63 6d 70 67 3a 20 25 73 29 } //1 Session started (v=%d %s; cmpg: %s)
		$a_01_18 = {6f 75 74 2d 73 65 73 73 69 6f 6e 73 2e 6c 6f 67 } //1 out-sessions.log
		$a_01_19 = {6d 61 69 6c 2e 72 75 } //1 mail.ru
		$a_01_20 = {47 2f 6d 3d 25 64 2c 20 54 3d 25 64 2c 20 47 3d 25 64 2c 20 42 3d 25 64 20 28 62 6c 3d 25 64 2c 20 6e 6f 75 73 65 72 3d 25 64 2c 20 6e 6f 6d 78 3d 25 64 2c 20 69 6f 65 72 72 3d 25 64 2c 20 65 72 72 3d 25 64 29 2c 20 74 68 3d 25 64 } //1 G/m=%d, T=%d, G=%d, B=%d (bl=%d, nouser=%d, nomx=%d, ioerr=%d, err=%d), th=%d
		$a_01_21 = {7b 72 6e 64 61 62 63 38 7d } //1 {rndabc8}
		$a_01_22 = {70 6f 73 74 6d 61 73 74 65 72 40 75 73 61 2e 6e 65 74 } //1 postmaster@usa.net
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1) >=22
 
}