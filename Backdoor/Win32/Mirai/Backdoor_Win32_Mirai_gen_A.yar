
rule Backdoor_Win32_Mirai_gen_A{
	meta:
		description = "Backdoor:Win32/Mirai.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 3d 00 00 "
		
	strings :
		$a_80_0 = {27 73 63 20 63 6f 6e 66 69 67 20 53 51 4c 53 45 52 56 45 52 41 47 45 4e 54 20 73 74 61 72 74 3d 20 61 75 74 6f 27 } //'sc config SQLSERVERAGENT start= auto'  1
		$a_80_1 = {2f 2f 25 73 3a 38 38 38 38 2f 75 70 73 2e 72 61 72 } ////%s:8888/ups.rar  1
		$a_80_2 = {2f 2f 25 73 3a 38 38 38 38 2f 77 70 64 2e 64 61 74 } ////%s:8888/wpd.dat  1
		$a_80_3 = {2f 2f 25 73 3a 38 38 38 38 2f 77 70 64 6d 64 35 2e 74 78 74 } ////%s:8888/wpdmd5.txt  1
		$a_80_4 = {2f 2f 64 6f 77 6e 32 2e 62 35 77 39 31 2e 63 6f 6d 3a 38 34 34 33 } ////down2.b5w91.com:8443  1
		$a_80_5 = {2f 73 68 65 6c 6c 3f 25 73 } ///shell?%s  1
		$a_80_6 = {3b 44 72 6f 70 20 50 72 6f 63 65 64 75 72 65 20 73 70 5f 70 61 73 73 77 6f 72 64 3b } //;Drop Procedure sp_password;  1
		$a_80_7 = {3b 65 78 65 63 20 73 70 5f 61 64 64 5f 6a 6f 62 73 65 72 76 65 72 } //;exec sp_add_jobserver  1
		$a_80_8 = {3b 45 58 45 43 20 73 70 5f 64 72 6f 70 6c 6f 67 69 6e } //;EXEC sp_droplogin  1
		$a_80_9 = {3b 65 78 65 63 28 40 61 29 3b } //;exec(@a);  1
		$a_80_10 = {3c 73 69 70 3a 63 61 72 6f 6c 40 63 68 69 63 61 67 6f 2e 63 6f 6d 3e } //<sip:carol@chicago.com>  1
		$a_80_11 = {40 6e 61 6d 65 3d 27 62 61 74 2e 65 78 65 27 2c 40 66 72 65 71 5f 74 79 70 65 3d 34 2c 40 61 63 74 69 76 65 5f 73 74 61 72 74 5f 64 61 74 65 } //@name='bat.exe',@freq_type=4,@active_start_date  1
		$a_80_12 = {40 73 68 65 6c 6c 20 49 4e 54 20 45 58 45 43 20 53 50 5f } //@shell INT EXEC SP_  1
		$a_80_13 = {5b 43 72 61 63 6b 65 72 3a 43 43 54 56 5d } //[Cracker:CCTV]  1
		$a_80_14 = {5b 43 72 61 63 6b 65 72 3a 4d 53 53 51 4c 5d } //[Cracker:MSSQL]  1
		$a_80_15 = {5b 43 72 61 63 6b 65 72 3a 4d 53 53 51 4c 5d 20 48 6f 73 74 3a 25 73 2c 20 62 6c 69 6e 64 45 78 65 63 20 43 4d 44 3a 20 25 73 } //[Cracker:MSSQL] Host:%s, blindExec CMD: %s  1
		$a_80_16 = {5b 43 72 61 63 6b 65 72 3a 52 44 50 5d } //[Cracker:RDP]  1
		$a_80_17 = {5b 43 72 61 63 6b 65 72 3a 54 65 6c 6e 65 74 5d } //[Cracker:Telnet]  1
		$a_80_18 = {5b 43 72 61 63 6b 65 72 5d } //[Cracker]  1
		$a_80_19 = {5b 63 53 65 72 76 69 63 65 5d } //[cService]  1
		$a_80_20 = {5b 45 78 65 63 43 6f 64 65 5d } //[ExecCode]  1
		$a_80_21 = {5b 45 78 65 63 43 6f 64 65 5d 41 55 54 48 4f 52 49 5a 41 54 49 4f 4e 20 5b 64 62 6f 5d 20 46 52 4f 4d 20 30 78 34 44 35 41 } //[ExecCode]AUTHORIZATION [dbo] FROM 0x4D5A  2
		$a_80_22 = {5b 49 70 46 65 74 63 68 65 72 5d } //[IpFetcher]  1
		$a_80_23 = {5b 4c 6f 67 67 65 72 5f 53 74 64 6f 75 74 5d } //[Logger_Stdout]  1
		$a_80_24 = {5b 53 63 61 6e 6e 65 72 5d } //[Scanner]  1
		$a_80_25 = {5b 53 65 72 76 65 72 41 67 65 6e 74 5d } //[ServerAgent]  1
		$a_80_26 = {5b 53 71 6c 53 74 6f 72 65 64 50 72 6f 63 65 64 75 72 65 31 5d } //[SqlStoredProcedure1]  1
		$a_80_27 = {5b 53 74 6f 72 65 64 50 72 6f 63 65 64 75 72 65 73 5d } //[StoredProcedures]  1
		$a_80_28 = {5b 54 50 3a 25 73 5d } //[TP:%s]  1
		$a_80_29 = {5b 54 50 3a 25 73 5d 20 25 64 20 74 68 72 65 61 64 73 20 63 72 65 61 74 65 64 } //[TP:%s] %d threads created  1
		$a_80_30 = {5b 55 70 64 61 74 65 54 68 72 65 61 64 3a 5d } //[UpdateThread:]  1
		$a_80_31 = {5c 52 75 6e 27 2c 27 72 75 6e 64 6c 6c 33 32 27 3b } //\Run','rundll32';  1
		$a_80_32 = {00 78 57 69 6e 57 70 64 53 72 76 00 } //  1
		$a_80_33 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 6b 75 67 6f 75 32 30 31 30 26 61 74 74 72 69 62 } //C:\Progra~1\kugou2010&attrib  1
		$a_80_34 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 6d 61 69 6e 73 6f 66 74 26 61 74 74 72 69 62 } //C:\Progra~1\mainsoft&attrib  1
		$a_80_35 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 73 68 65 6e 67 64 61 26 61 74 74 72 69 62 } //C:\Progra~1\shengda&attrib  1
		$a_80_36 = {63 6d 64 33 3a 5b 25 73 5d } //cmd3:[%s]  1
		$a_80_37 = {43 72 61 63 6b 65 72 57 4d 49 } //CrackerWMI  1
		$a_80_38 = {63 72 61 7a 79 20 65 78 63 65 70 74 69 6f 6e 21 21 21 } //crazy exception!!!  1
		$a_80_39 = {64 62 63 63 20 61 64 64 65 78 74 65 6e 64 65 64 70 72 6f 63 20 28 27 73 70 5f } //dbcc addextendedproc ('sp_  1
		$a_80_40 = {64 62 63 63 20 61 64 64 65 78 74 65 6e 64 65 64 70 72 6f 63 20 28 27 78 70 5f } //dbcc addextendedproc ('xp_  1
		$a_80_41 = {64 65 63 6c 61 72 65 20 40 61 20 76 61 72 63 68 61 72 28 38 30 30 30 29 3b 73 65 74 20 40 61 3d 30 78 } //declare @a varchar(8000);set @a=0x  1
		$a_80_42 = {44 45 4d 41 4e 44 5f 41 43 54 49 56 45 28 69 64 3d 30 78 25 78 29 } //DEMAND_ACTIVE(id=0x%x)  1
		$a_80_43 = {44 52 49 56 45 52 3d 7b 53 51 4c 20 53 65 72 76 65 72 7d } //DRIVER={SQL Server}  1
		$a_80_44 = {44 52 4f 50 20 41 53 53 45 4d 42 4c 59 20 45 78 65 63 43 6f 64 65 } //DROP ASSEMBLY ExecCode  1
		$a_80_45 = {44 72 6f 70 20 50 72 6f 63 65 64 75 72 65 20 73 70 5f } //Drop Procedure sp_  1
		$a_80_46 = {44 72 6f 70 20 50 72 6f 63 65 64 75 72 65 20 78 70 5f } //Drop Procedure xp_  1
		$a_80_47 = {65 63 68 6f 20 2d 6e 65 20 27 25 73 27 20 25 73 20 75 70 6e 70 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 45 43 43 48 49 } //echo -ne '%s' %s upnp; /bin/busybox ECCHI  1
		$a_80_48 = {69 73 5f 73 72 76 72 6f 6c 65 6d 65 6d 62 65 72 28 40 72 6f 6c 65 6e 61 6d 65 29 } //is_srvrolemember(@rolename)  1
		$a_80_49 = {4d 45 4d 42 4c 54 28 6f 70 3d 30 78 25 78 2c 78 3d 25 64 2c 79 3d 25 64 2c 63 78 3d 25 64 2c 63 79 3d 25 64 2c 69 64 3d 25 64 2c 69 64 78 3d 25 64 29 } //MEMBLT(op=0x%x,x=%d,y=%d,cx=%d,cy=%d,id=%d,idx=%d)  1
		$a_80_50 = {00 4d 49 52 41 49 00 } //  2
		$a_80_51 = {72 6d 20 25 73 2f 2e 74 3b 20 72 6d 20 25 73 2f 2e 73 68 3b 20 72 6d 20 25 73 2f 2e 68 75 6d 61 6e } //rm %s/.t; rm %s/.sh; rm %s/.human  1
		$a_80_52 = {73 63 31 20 73 74 6f 70 20 73 68 61 72 65 64 61 63 63 65 73 73 26 73 63 20 73 74 6f 70 20 31 4d 70 73 53 76 63 26 73 63 20 63 6f 6e 66 69 67 20 31 4d 70 73 53 76 63 20 73 74 61 72 74 3d } //sc1 stop sharedaccess&sc stop 1MpsSvc&sc config 1MpsSvc start=  1
		$a_80_53 = {54 61 73 6b 5f 43 72 61 63 6b 5f 54 65 6c 6e 65 74 3a 3a 69 6e 66 65 63 74 } //Task_Crack_Telnet::infect  1
		$a_80_54 = {74 69 6d 65 6f 75 74 2c 74 68 65 20 72 65 6d 6f 74 65 20 73 65 72 76 65 72 20 25 73 20 64 6f 73 65 6e 27 74 20 72 65 73 70 6f 6e 64 21 } //timeout,the remote server %s dosen't respond!  2
		$a_80_55 = {55 50 4c 4f 41 44 5f 57 47 45 54 } //UPLOAD_WGET  1
		$a_80_56 = {75 73 65 20 6d 73 64 62 3b 65 78 65 63 20 73 70 5f 61 64 64 5f 6a 6f 62 20 27 } //use msdb;exec sp_add_job '  1
		$a_80_57 = {78 70 5f 63 6d 64 73 68 65 6c 6c } //xp_cmdshell  1
		$a_80_58 = {7d 3b 50 57 44 3d 7b } //};PWD={  1
		$a_03_59 = {73 65 74 79 ?? ?? ?? 62 64 65 74 } //1
		$a_03_60 = {75 65 73 70 ?? ?? ?? 65 6d 6f 73 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1+(#a_80_21  & 1)*2+(#a_80_22  & 1)*1+(#a_80_23  & 1)*1+(#a_80_24  & 1)*1+(#a_80_25  & 1)*1+(#a_80_26  & 1)*1+(#a_80_27  & 1)*1+(#a_80_28  & 1)*1+(#a_80_29  & 1)*1+(#a_80_30  & 1)*1+(#a_80_31  & 1)*1+(#a_80_32  & 1)*1+(#a_80_33  & 1)*1+(#a_80_34  & 1)*1+(#a_80_35  & 1)*1+(#a_80_36  & 1)*1+(#a_80_37  & 1)*1+(#a_80_38  & 1)*1+(#a_80_39  & 1)*1+(#a_80_40  & 1)*1+(#a_80_41  & 1)*1+(#a_80_42  & 1)*1+(#a_80_43  & 1)*1+(#a_80_44  & 1)*1+(#a_80_45  & 1)*1+(#a_80_46  & 1)*1+(#a_80_47  & 1)*1+(#a_80_48  & 1)*1+(#a_80_49  & 1)*1+(#a_80_50  & 1)*2+(#a_80_51  & 1)*1+(#a_80_52  & 1)*1+(#a_80_53  & 1)*1+(#a_80_54  & 1)*2+(#a_80_55  & 1)*1+(#a_80_56  & 1)*1+(#a_80_57  & 1)*1+(#a_80_58  & 1)*1+(#a_03_59  & 1)*1+(#a_03_60  & 1)*1) >=8
 
}