
rule Trojan_Win32_Laziok_gen_A{
	meta:
		description = "Trojan:Win32/Laziok.gen.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 19 00 00 01 00 "
		
	strings :
		$a_80_0 = {26 64 61 74 61 32 3d 78 78 78 26 48 57 49 44 3d } //&data2=xxx&HWID=  01 00 
		$a_80_1 = {26 64 69 73 6b 68 61 72 64 3d } //&diskhard=  01 00 
		$a_80_2 = {26 47 72 61 62 44 61 74 61 3d } //&GrabData=  01 00 
		$a_80_3 = {26 6d 65 6d 6f 69 72 65 52 41 4d 62 79 74 65 73 3d } //&memoireRAMbytes=  01 00 
		$a_80_4 = {26 70 61 72 65 66 69 72 65 3d } //&parefire=  01 00 
		$a_80_5 = {26 77 65 62 6e 61 76 69 67 3d } //&webnavig=  01 00 
		$a_80_6 = {34 31 34 66 69 6c 65 68 30 73 74 2e 65 78 65 } //414fileh0st.exe  01 00 
		$a_80_7 = {5c 61 64 6d 69 6e 2e 65 78 65 } //\admin.exe  02 00 
		$a_80_8 = {5c 61 7a 69 6f 6b 6c 6d 70 78 5c } //\azioklmpx\  01 00 
		$a_80_9 = {5c 68 7a 69 64 2e 74 78 74 } //\hzid.txt  01 00 
		$a_80_10 = {5c 6a 62 69 67 69 2e 64 6c 6c } //\jbigi.dll  01 00 
		$a_80_11 = {5c 53 79 73 74 65 6d 5c 6f 75 74 70 75 74 63 72 61 6d 69 2e 74 78 74 } //\System\outputcrami.txt  01 00 
		$a_80_12 = {5c 76 61 6c 75 65 2e 74 78 74 } //\value.txt  01 00 
		$a_80_13 = {63 6c 69 63 6b 2e 70 61 63 6b } //click.pack  01 00 
		$a_80_14 = {64 5f 65 6c 61 79 2e 70 68 70 } //d_elay.php  01 00 
		$a_80_15 = {44 65 73 69 6e 74 61 6c 6c } //Desintall  01 00 
		$a_80_16 = {44 6c 45 78 65 00 } //DlExe  01 00 
		$a_80_17 = {44 6c 49 6e 6a 00 } //DlInj  01 00 
		$a_80_18 = {44 6c 4a 61 72 00 } //DlJar  01 00 
		$a_80_19 = {66 5f 69 5f 6c 5f 65 5f 68 5f 6f 5f 73 5f 74 2e 70 68 70 } //f_i_l_e_h_o_s_t.php  01 00 
		$a_80_20 = {69 32 70 2f 69 6e 73 74 61 6c 6c 5f 69 32 70 5f 73 65 72 76 69 63 65 5f 77 69 6e 6e 74 2e 62 61 74 } //i2p/install_i2p_service_winnt.bat  01 00 
		$a_80_21 = {69 32 70 2f 73 65 74 5f 63 6f 6e 66 69 67 5f 64 69 72 5f 66 6f 72 5f 6e 74 5f 73 65 72 76 69 63 65 2e 62 61 74 } //i2p/set_config_dir_for_nt_service.bat  01 00 
		$a_80_22 = {4a 57 46 77 63 47 52 68 64 47 45 6c 41 41 3d 3d } //JWFwcGRhdGElAA==  01 00 
		$a_80_23 = {6b 69 6c 6c 79 6f 75 72 74 76 5f 61 74 5f 6d 61 69 6c 2e 69 32 70 } //killyourtv_at_mail.i2p  01 00 
		$a_80_24 = {76 65 72 69 66 2e 70 68 70 } //verif.php  00 00 
		$a_00_25 = {5d 04 00 00 b8 34 } //03 80 
	condition:
		any of ($a_*)
 
}